# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Primary: people who work with AI coding agents (Claude Code, Z Code, Codex
and other harnesses) and want to know what is wrong with their working
folder without reading a technical report. Most of them do not work with
code: they ask in plain words ("audit my workspace") and read a
plain-language answer.

The visual explorer serves the reader who digs into one audit: the
maintainer of a workspace, or the person who just read the plain report and
wants to see where a finding sits, which files an agent tool really loads,
or what changed since the last audit.

## Product Purpose

agents-doctor audits the folder where a person works with AI agents and
says, in plain words, what is wrong, what to start with and what can be
improved: leaked passwords and keys, broken or conflicting agent
instructions, skills that do not load, unsafe tool settings, folders
without a backup, junk and extra tokens. The scanner is deterministic and
read-only; a short digest and a plain-language report are written for
people, a technical report and the scan for tools.

Success: a person who does not work with code understands the main problem
and the first step, and the audit has deleted or changed nothing.

## Positioning

One deterministic scanner behind three doors: the agent skill (a
plain-language answer in chat), the visual explorer in the browser, and a
CI action. The audit never changes the folder; every fix is planned first,
applied only after an explicit confirmation, and goes to a restorable
trash.

## Operating Context

- Runs locally through an agent harness or the command line: no network,
  no dependencies (standard-library Python).
- One audit command writes three files into `.agents-doctor/` of the
  audited folder: `REPORT.md` (plain language), `AUDIT.md` (technical),
  `scan.json` (the full scan).
- The visual explorer (`agents_doctor.py ui <root>`) serves one scan on
  127.0.0.1, read-only: Overview, Tree, TreeMap, Instructions, Findings,
  Simulate, Compare, History, a masked file preview and a finding card.
- English and Russian for the plain-language report and the digest.

## Capabilities and Constraints

- Standard library only in the scanner. The web UI is plain HTML, CSS and
  JavaScript: no framework, no external requests; the server sends a
  Content-Security-Policy.
- Color is never the only signal: every status also carries a text label
  and/or a glyph.
- Secrets are masked in every output and on every surface.
- 29 end-to-end Playwright tests pin the behaviour and the selectors of
  the visual explorer.
- Undecided: whether the visual explorer gets a simplified first screen
  for non-technical readers. Asked on 2026-11-27; the user chose "look
  only" for the redesign in progress and left the structure as it is.

## Brand Commitments

- Name: agents-doctor. The favicon and the app icon are the author's own
  pixel drawing (a "D" with a medical cross): keep them unless the author
  asks for a change.
- Visual direction, pinned by the user on 2026-11-27: «в стиле apple»,
  «macOS-приложение»; "only the look" changes, the structure and the
  behaviour of the visual explorer stay.
- Typeface: the system font stack (San Francisco on Apple devices) with
  Inter bundled for other systems. Inter ships under the SIL Open Font
  License together with its licence file.

## Evidence on Hand

- Synthetic workspaces with expected scans: `llm-eval/fixtures/`,
  `tests/integration/`, `bench/`; sample reports in `docs/`.
- The explorer shows the scan of the audited folder and nothing else. No
  user data, testimonials or benchmarks may be invented for it.

## Product Principles

1. Not checked is not fine: say what could not be verified and why.
2. Names, not codes: people read words, codes are for commands.
3. The audit never changes anything; every fix is planned, confirmed and
   reversible.
4. Secrets stay secret, in every output and on every surface.
5. Plain words first; depth for the reader who digs.

## Accessibility & Inclusion

The explorer works with the keyboard and the screen reader (roles, labels,
a visible focus ring, a reduced-motion media query). Text keeps its
contrast in the light and in the dark appearance, and no state is conveyed
by color alone.
