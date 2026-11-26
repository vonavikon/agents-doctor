# Agents Doctor

Generated 2026-11-26T14:00:09+03:00 | schema 1.0 | rules 3.1.0 | 18 files scanned | 0.64 s

## Executive Summary

Overall status: FAIL.
The scan produced 34 findings (2 critical, 4 high, 10 medium, 16 low, 2 info).
Most important finding: SEC-001 - Exposed secret in .mcp.json:6.
Gates: 6 fail, 2 warn, 1 pass, 0 unknown.
Secret values are redacted in this report; only masks and fingerprints are recorded.

## Overall Workspace Health

Status: FAIL.
- Workspace structure (fail): drifted config pairs: 1
- Rules consistency (fail): instruction files checked: 5, dead references: 4
- Directory ownership and discoverability (fail): heavy dirs outside git: 1
- Skills and agent capabilities (fail): skills checked: 3, frontmatter failures: 0, unverified: 0
- Secrets and Git security (fail): secrets found in workspace files: 1
- Git hygiene (warn): repos with uncommitted work: 1 of 3
- Agent environment governance (fail): governance notes: 1
- Workspace health and maintainability (warn): classified junk items: 5

## Gate Results

| # | Gate | Status | Key evidence |
| --- | --- | --- | --- |
| G1 | Workspace structure | fail | `drifted config pairs: 1` |
| G2 | Configuration integrity | pass | `config files parsed: 1, broken: 0` |
| G3 | Rules consistency | fail | `instruction files checked: 5, dead references: 4` |
| G4 | Directory ownership and discoverability | fail | `heavy dirs outside git: 1` |
| G5 | Skills and agent capabilities | fail | `skills checked: 3, frontmatter failures: 0, unverified: 0` |
| G6 | Secrets and Git security | fail | `secrets found in workspace files: 1` |
| G7 | Git hygiene | warn | `repos with uncommitted work: 1 of 3` |
| G8 | Agent environment governance | fail | `governance notes: 1` |
| G9 | Workspace health and maintainability | warn | `classified junk items: 5` |

## Critical Findings

| fid | severity | title | location |
| --- | --- | --- | --- |
| DIR-001 | high | Drifted AGENTS.md/CLAUDE.md pair in tools | tools |
| RUL-009 | high | Two rule sources at tools | tools |
| SEC-001 | critical | Exposed secret in .mcp.json:6 | .mcp.json:6 |
| SEC-002 | critical | Secret tracked in git at legacy-crm: config.py:1 | config.py:1 |
| SKL-003 | high | Description of skill 'x-helper' is 1190 chars, limit 1024 | .agents/skills/x-helper/SKILL.md |
| SKL-005 | high | Diverged copies of skill 'x-helper' | ~/.zcode/skills/x-helper/SKILL.md, .agents/skills/x-helper/SKILL.md |

## All Findings

| fid | gate | severity | status | title | location | what to do |
| --- | --- | --- | --- | --- | --- | --- |
| SEC-001 | G6 | critical | fail | Exposed secret in .mcp.json:6 | .mcp.json:6 | Rotate the secret at its provider, remove it from the file and purge it from history. |
| SEC-002 | G6 | critical | fail | Secret tracked in git at legacy-crm: config.py:1 | config.py:1 | Rotate the secret, `git rm --cached` the file and purge the history. |
| DIR-001 | G1 | high | fail | Drifted AGENTS.md/CLAUDE.md pair in tools | tools | Keep one file as the source and turn the other into a pointer to it. |
| RUL-009 | G3 | high | fail | Two rule sources at tools | tools | Keep one file as the source and make the other a pointer (structure view: G1). |
| SKL-003 | G5 | high | fail | Description of skill 'x-helper' is 1190 chars, limit 1024 | .agents/skills/x-helper/SKILL.md | Shorten the description; move details into the skill body. |
| SKL-005 | G5 | high | fail | Diverged copies of skill 'x-helper' | ~/.zcode/skills/x-helper/SKILL.md, .agents/skills/x-helper/SKILL.md | Pick one canonical location and delete or sync the rest. |
| DIR-002 | G4 | medium | fail | Heavy directory outside git: exports | exports | Move it under version control, archive it, or delete it. |
| GOV-001 | G8 | medium | fail | Instructions maintained for a dead harness | tools\CLAUDE.md: maintained for a dead harness, claude inactive for 200 days | Remove the file or convert it to a pointer under the harness actually in use. |
| RUL-001 | G3 | medium | fail | Dead path in AGENTS.md: scripts/deploy.sh | AGENTS.md | Fix or remove the reference. |
| RUL-002 | G3 | medium | fail | Dead path in AGENTS.md: docs/runbook.md | AGENTS.md | Fix or remove the reference. |
| RUL-003 | G3 | medium | fail | Dead path in tools\AGENTS.md: docs/api.md | tools/AGENTS.md | Fix or remove the reference. |
| RUL-004 | G3 | medium | fail | Dead path in tools\CLAUDE.md: config/defaults.yaml | tools/CLAUDE.md | Fix or remove the reference. |
| RUL-007 | G3 | medium | warn | Instruction file is mostly noise (signal ratio 0%) | AGENTS.md | Trim to actionable rules: what to run, what to avoid, where files are. |
| RUL-010 | G3 | medium | warn | AGENTS.md chain over 32768 bytes | . | Trim the chain or split nested instructions into linked files. |
| RUL-011 | G3 | medium | warn | AGENTS.md chain over the Codex context budget | AGENTS.md | shorten the files or move subtree-specific rules into nested AGENTS.md so only the active subtree pays for them. |
| SEC-003 | G6 | medium | warn | No secret-prevention mechanism found | no pre-commit/pre-push hook with secret scan in any repository | Install a pre-commit secret scan (gitleaks or equivalent) in every active repository. |
| DIR-003 | G4 | low | warn | 5 top-level folders outside version control | .agents | Decide for each folder: make it a repo, move it into one, or remove it. |
| GIT-001 | G7 | low | warn | Uncommitted work in legacy-crm | legacy-crm | Commit or stash the changes; push if the repo has a remote. |
| GIT-002 | G7 | low | warn | No .gitignore in legacy-crm-hotfix | legacy-crm-hotfix | Add a .gitignore covering build dirs and local config files. |
| GIT-003 | G7 | low | warn | No .gitignore in tools | tools | Add a .gitignore covering build dirs and local config files. |
| GIT-004 | G7 | low | warn | Multiple checkouts of one remote: legacy-crm, legacy-crm-hotfix | https://gitlab.example.com/legacy/crm.git | Keep one checkout or make the others deliberate worktrees. |
| HLTH-001 | G9 | low | warn | Unused data (potentially_unused): documents\отчет-v1 (копия).pdf | documents/отчет-v1 (копия).pdf | Review, then archive or delete. |
| HLTH-002 | G9 | low | warn | Unused data (potentially_unused): screenshots\IMG_001.jpg | screenshots/IMG_001.jpg | Review, then archive or delete. |
| HLTH-003 | G9 | low | warn | Unused data (potentially_unused): screenshots\IMG_2022_09_01.jpg | screenshots/IMG_2022_09_01.jpg | Review, then archive or delete. |
| HLTH-004 | G9 | low | warn | Unused data (potentially_unused): screenshots\IMG_2023_04_11.jpg | screenshots/IMG_2023_04_11.jpg | Review, then archive or delete. |
| HLTH-005 | G9 | low | warn | Unused data (potentially_unused): старые презентации | старые презентации | Review, then archive or delete. |
| HLTH-007 | G9 | low | warn | File over 5 MB outside git: exports\data-dump.csv | exports/data-dump.csv | Move under version control (git-lfs if needed) or delete. |
| RUL-005 | G3 | low | warn | Generic boilerplate in AGENTS.md: 'структура репозитория' | AGENTS.md | Replace the boilerplate with project-specific rules or drop it. |
| RUL-006 | G3 | low | warn | Instruction file over 16 KB: AGENTS.md | AGENTS.md | Split the file: keep rules auto-loaded, move the rest to linked docs. |
| SKL-001 | G5 | low | warn | No triggers in the description of skill 'x-helper' | ~/.zcode/skills/x-helper/SKILL.md | Add a trigger phrase ("use when ...") to the description. |
| SKL-002 | G5 | low | warn | No triggers in the description of skill 'doc-helper' | .agents/skills/doc-helper/SKILL.md | Add a trigger phrase ("use when ...") to the description. |
| SKL-004 | G5 | low | warn | No triggers in the description of skill 'x-helper' | .agents/skills/x-helper/SKILL.md | Add a trigger phrase ("use when ...") to the description. |
| HLTH-006 | G9 | info | pass | 1 empty directories | Новая папка | Optional: remove the empty directories. |
| RUL-008 | G3 | info | pass | Short instruction file, few concrete rules (signal ratio 20%) | tools/AGENTS.md | A short pointer file is fine as it is; check it only if it was meant to hold rules. |

## Recommended Actions

1. [SEC-001]: .mcp.json:6: Rotate the secret at its provider, remove it from the file and purge it from history.
2. [SEC-002]: config.py:1: Rotate the secret, `git rm --cached` the file and purge the history.
3. [DIR-001]: Keep one file as the source and turn the other into a pointer to it.
4. [RUL-009]: Keep one file as the source and make the other a pointer (structure view: G1).
5. [SKL-003]: Shorten the description; move details into the skill body.
6. [SKL-005]: Pick one canonical location and delete or sync the rest.

Read-only audit: nothing was modified. Rerun with --baseline to track drift.
