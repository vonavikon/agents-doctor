---
version: 1
slug: "skills-agents-doctor-scripts-ui-static-index-html"
primary_target: "skills/agents-doctor/scripts/ui/static/index.html"
related_targets: ["skills/agents-doctor/scripts/ui/static/style.css","skills/agents-doctor/scripts/ui/static/app.js","skills/agents-doctor/scripts/ui/server.py"]
---

# Visual workspace explorer

Scope: the single-page explorer served by `agents_doctor.py ui <root>` on
127.0.0.1. Files: `skills/agents-doctor/scripts/ui/static/index.html`,
`style.css`, `app.js`, the bundled font under `static/assets/fonts/`, and
`ui/server.py` only as far as it serves the font with the right media type.
Visitor mode: Operate.

## Audience and job

The reader who digs into one audit: the maintainer of a workspace, or the
person who just read the plain report. They open the explorer to see which
gates fail and why, where a finding sits in the tree (file and line, with a
masked preview), which instruction files each agent tool really loads, and
what changed since the previous audit. Sessions are short and repeated.

## Task, states, constraints

- Task: move from a red or amber gate to the exact file and line, then to a
  fix plan; compare two audits; read the trend.
- Important states: loading, empty (no findings, no history, Compare without
  a baseline), error (file cannot be opened), filtered to zero, long paths,
  Cyrillic and other non-Latin file names, selected and flagged rows.
- Only the look changes. The DOM structure, every id, every class name, the
  roles and aria attributes, the keyboard model, the copy and the behaviour
  stay as they are. Eight views stay at the top: Overview, Tree, TreeMap,
  Instructions, Findings, Simulate, Compare, History.
- Plain HTML, CSS and JavaScript; no framework, no network requests, no
  dependencies. The server sends a Content-Security-Policy
  (`default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:`).
- Colour is never the only signal: every status and severity keeps its word
  and glyph.
- The Playwright end-to-end suite and the unit tests pin selectors and text
  (for example `.status-badge .st-glyph` must keep a non-empty text in all
  nine gate rows).
- Light and dark appearance follow the system (`prefers-color-scheme`);
  there is no manual theme switch in this round.

## Content and proof

Real scan data only: gates G1 to G9 with status and confidence, the health
score with its components, detected environments, findings with file and
line, the instruction chains per harness, the masked file preview, the diff
against a baseline, the recorded audits. No invented numbers, quotes or
promotional copy anywhere in the explorer.

## Direction and memorable moment

A native macOS utility window for one audit, in light and in dark appearance.
The memorable moment is the unified toolbar that carries the whole tool:
back and forward, the view switcher with an icon above each label, the
product name as the centred window title, Rescan at the right; below it the
health score drawn as a rounded Activity-style ring beside its component
bars.

## Unresolved decisions

- Version number and release of this change (user decides at push time).
- A simplified first screen for non-technical readers (undecided in
  PRODUCT.md; not part of this round).

## Direction contract

THESIS: The explorer reads as a native macOS utility window for one audit, not as a web dashboard: one toolbar carries every view, content sits in inset grouped surfaces, and colour only marks state. It refuses the dark developer-console look (13px monospace everywhere, grey on grey) and the generic admin dashboard of floating shadowed cards.

OWN-WORLD: Light: window #f5f5f7, surfaces #ffffff, hairline separators, text #1d1d1f and secondary #6e6e73 (built as #66666b, which keeps 4.5:1 on the toolbar strip). Dark: window #1e1e20, surfaces #2c2c2e, text #f5f5f7 and secondary #98989d (built as #a6a6ab, same reason). Accent is system blue (#007aff light, #0a84ff dark); state colours are the system red, orange, yellow, green, blue, purple and grey. San Francisco on Apple devices, bundled Inter elsewhere; a fixed 11/12/13/15/28 scale, semibold titles, monospace only for paths, identifiers, code, measurements and formula notes. Push buttons, a segmented control, pop-up buttons, search fields and capsule filter chips; inset grouped cards with a 10px radius and a hairline border; selection is an accent-tinted rounded row.

STORY: The reader lands on the Overview, reads the gate table top to bottom and knows which gates fail and how sure the scanner is; one click on a finding opens the card, one click on a file opens the masked preview; Compare and History answer what changed. Every state is legible in words; colour repeats it.

FIRST VIEWPORT (1440x900): a 52px toolbar across the full width: back and forward at the left, then the view switcher as eight icon-and-label items with the active one tinted; the title "agents-doctor" centred; Rescan as a bordered button at the right. Under it a 28px status strip with the root path, scan time, rules version and findings count, then the severity filter as capsule chips with counts. The Overview fills the rest: a row of six inset stat cards (label over a 28px number), the health score ring at the left with six component bars beside it, detected environments as capsules, and the gate table as an inset grouped table with a status word and a trailing confidence value. The primary action of the toolbar, Rescan, sits at the top right as a bordered push button; the one filled (default) button of the page is Run, in Simulate.

FORM: pinned whole by the user, no roll. seed: none (pinned). The user's request, verbatim: «я хосчу чтобы ты с помощью плагиа impaaccable причесал полностиью всю визуальную часть, сделла бы в стиле apple»; answers to the structured questions, verbatim: «macOS-приложение», «Только вид» (structure and behaviour of the web explorer stay), «Inter» (bundle Inter for non-Apple systems, San Francisco on Apple devices).

FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance
